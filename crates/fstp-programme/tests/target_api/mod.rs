//! The one place the W1a tests name the designed `fstp-programme` API.
//!
//! M4 design section 3.1 states most of the API. Where it is silent, the
//! test author chose the names below, and the lane report lists each gap:
//!
//! - `Step::number(self) -> u8`, the creator step 1 to 10;
//! - `FieldId::ALL`, every field id;
//! - `FunderProfile::horizon_europe() -> FunderProfile`;
//! - `CompileIds::new(programme, version, parent)`;
//! - `encode_spec(&ProgrammeSpec) -> String`, the canonical RFC 8785 text;
//! - `decode_spec(&[u8])`, as the W0 stub has it;
//! - `decode_field_value(FieldId, &[u8])`, `encode_field_value(&FieldValue)
//!   -> String` and `FieldValue::field(&self) -> FieldId`.
//!
//! Errors are only formatted with `Debug`, so their types are free.
//!
//! The fixture `fixtures/supersafe.programme.json` is one canonical JSON
//! object with exactly two members. `"spec"` is the spec in the canonical
//! form `encode_spec` writes. `"provenance"` maps each synthetic
//! parameter id, such as `"P-58"`, or synthetic artefact field path, such
//! as `"funder.action_number"`, to an object holding `"synthetic": true`
//! (M4 design section 3.1, synthetic placeholders).

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_json::{Number, Value};
use fstp_programme::{
    CompileIds, Compiled, FIELDS, FieldId, FieldKind, FunderProfile, ProgrammeSpec,
};
use fstp_prop::Gen;

/// The programme id every test compiles for.
pub(crate) const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(0x5afe_0000_0001);
/// The policy version id every test compiles to.
pub(crate) const VERSION: PolicyVersionId = PolicyVersionId::from_raw(0x5afe_0000_0002);

/// The shell-supplied ids for a first version.
pub(crate) fn ids() -> CompileIds {
    CompileIds::new(PROGRAMME, VERSION, None)
}

/// The Horizon Europe funder profile SuperSAFE uses (P-53).
pub(crate) fn profile() -> FunderProfile {
    FunderProfile::horizon_europe()
}

/// `compile` with the Horizon Europe profile and [`ids`].
pub(crate) fn compile(spec: &ProgrammeSpec) -> Result<Compiled, String> {
    fstp_programme::compile(spec, &profile(), ids()).map_err(|e| format!("compile: {e:?}"))
}

/// `compile` with the Horizon Europe profile and the given ids.
pub(crate) fn compile_with(spec: &ProgrammeSpec, ids: CompileIds) -> Result<Compiled, String> {
    fstp_programme::compile(spec, &profile(), ids).map_err(|e| format!("compile: {e:?}"))
}

/// `decompile` of everything `compile` returned.
pub(crate) fn decompile(c: &Compiled) -> ProgrammeSpec {
    fstp_programme::decompile(&c.policy, &c.artefacts, &c.unset)
}

/// `decompile` with another set of unset fields.
pub(crate) fn decompile_unset(c: &Compiled, unset: &BTreeSet<FieldId>) -> ProgrammeSpec {
    fstp_programme::decompile(&c.policy, &c.artefacts, unset)
}

/// `decode_spec`, with the error formatted.
pub(crate) fn decode(bytes: &[u8]) -> Result<ProgrammeSpec, String> {
    fstp_programme::decode_spec(bytes).map_err(|e| format!("decode_spec: {e:?}"))
}

/// `encode_spec`.
pub(crate) fn encode(spec: &ProgrammeSpec) -> String {
    fstp_programme::encode_spec(spec)
}

/// Every field id of the `FIELDS` table, in table order.
pub(crate) fn field_ids() -> Vec<FieldId> {
    FIELDS.iter().map(|f| f.id).collect()
}

/// The `"<step>.<member>"` path of every artefact field, as the fixture's
/// provenance block names one.
pub(crate) fn artefact_keys() -> BTreeSet<String> {
    FIELDS
        .iter()
        .filter(|f| f.kind == FieldKind::Artefact)
        .map(|f| format!("{}.{}", f.step.name(), f.id.name()))
        .collect()
}

/// The path of the SuperSAFE fixture.
pub(crate) fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/supersafe.programme.json")
}

/// The fixture file's text.
pub(crate) fn fixture_text() -> Result<String, String> {
    let path = fixture_path();
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The fixture file as JSON.
pub(crate) fn fixture() -> Result<Value, String> {
    fstp_json::parse_str(&fixture_text()?).map_err(|e| format!("fixture is not JSON: {e:?}"))
}

/// The fixture's `"spec"` member.
pub(crate) fn fixture_spec_value() -> Result<Value, String> {
    fixture()?
        .get("spec")
        .cloned()
        .ok_or_else(|| "the fixture has no \"spec\" member".to_owned())
}

/// The canonical text of the fixture's `"spec"` member.
pub(crate) fn fixture_spec_text() -> Result<String, String> {
    fstp_json::to_canonical(&fixture_spec_value()?).map_err(|e| format!("spec member: {e:?}"))
}

/// The fixture's spec, decoded.
pub(crate) fn fixture_spec() -> Result<ProgrammeSpec, String> {
    decode(fixture_spec_text()?.as_bytes())
}

/// The fixture's spec, compiled.
pub(crate) fn fixture_compiled() -> Result<Compiled, String> {
    compile(&fixture_spec()?)
}

// ---------------------------------------------------------------------------
// JSON paths and leaf edits, for generated specs and the strictness tests
// ---------------------------------------------------------------------------

/// One step of a path into a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    /// An object member.
    Key(String),
    /// An array element.
    Index(usize),
}

/// The value at `path`, for editing.
pub(crate) fn at_mut<'a>(v: &'a mut Value, path: &[Seg]) -> Option<&'a mut Value> {
    let mut cur = v;
    for seg in path {
        cur = match (seg, cur) {
            (Seg::Key(k), Value::Object(o)) => o.get_mut(k)?,
            (Seg::Index(i), Value::Array(a)) => a.get_mut(*i)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Every path in `v` with the value it leads to, root first.
pub(crate) fn paths(v: &Value) -> Vec<(Vec<Seg>, Value)> {
    let mut out = Vec::new();
    let mut stack: Vec<(Vec<Seg>, &Value)> = vec![(Vec::new(), v)];
    while let Some((path, v)) = stack.pop() {
        match v {
            Value::Object(o) => {
                for (k, child) in o.iter() {
                    let mut p = path.clone();
                    p.push(Seg::Key(k.to_owned()));
                    stack.push((p, child));
                }
            }
            Value::Array(a) => {
                for (i, child) in a.iter().enumerate() {
                    let mut p = path.clone();
                    p.push(Seg::Index(i));
                    stack.push((p, child));
                }
            }
            _ => {}
        }
        out.push((path, v.clone()));
    }
    out
}

/// Whether `s` is spelled as an ADR-006 EUR amount: `(0|[1-9][0-9]*)` then
/// a full stop and two digits.
pub(crate) fn is_amount_text(s: &str) -> bool {
    let Some((int, frac)) = s.split_once('.') else {
        return false;
    };
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    digits(int) && digits(frac) && frac.len() == 2 && (int == "0" || !int.starts_with('0'))
}

/// `v` as compact JSON text, keeping number lexemes as written.
pub(crate) fn compact(v: &Value) -> Vec<u8> {
    fstp_json::to_compact(v).into_bytes()
}

/// A generated ADR-006 EUR amount text.
fn gen_amount(g: &mut Gen) -> String {
    let whole = g.u32_in(0..=2_000_000);
    let cents = g.u8_in(0..=99);
    format!("{whole}.{cents:02}")
}

/// Edits one leaf or array of `v`, chosen by `g`, keeping its JSON type
/// most of the time. Strings that look like amounts get another amount.
fn mutate_once(g: &mut Gen, v: &mut Value, strings: &[String]) {
    let candidates: Vec<(Vec<Seg>, Value)> = paths(v)
        .into_iter()
        .filter(|(p, x)| {
            !p.is_empty()
                && match x {
                    Value::Array(a) => !a.is_empty(),
                    Value::Object(_) => false,
                    _ => true,
                }
        })
        .collect();
    if candidates.is_empty() {
        return;
    }
    let (path, old) = g.pick(&candidates).clone();
    let new = match old {
        Value::Bool(b) => Value::Bool(!b),
        Value::Number(_) => Value::from(g.i64_in(-30..=120)),
        Value::String(s) if is_amount_text(&s) => Value::String(gen_amount(g)),
        Value::String(_) => match g.weighted(&[1, 1]) {
            0 if !strings.is_empty() => Value::String(g.pick(strings).clone()),
            _ => Value::String(g.string(0..=24)),
        },
        Value::Array(a) => {
            let mut items = a.into_vec();
            let at = g.usize_in(0..=items.len().saturating_sub(1));
            if g.bool() {
                if let Some(x) = items.get(at).cloned() {
                    items.push(x);
                }
            } else if at < items.len() {
                items.remove(at);
            }
            Value::from(items)
        }
        other => other,
    };
    if let Some(slot) = at_mut(v, &path) {
        *slot = new;
    }
}

/// Every string in `v`.
pub(crate) fn strings_in(v: &Value) -> Vec<String> {
    paths(v)
        .into_iter()
        .filter_map(|(_, x)| match x {
            Value::String(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// A spec made from `base` (the fixture's spec member) with zero to three
/// leaf edits, or `None` when `decode_spec` rejects the edited text.
pub(crate) fn gen_spec(g: &mut Gen, base: &Value, strings: &[String]) -> Option<ProgrammeSpec> {
    let mut v = base.clone();
    let edits = g.weighted(&[3, 2, 1, 1]);
    for _ in 0..edits {
        mutate_once(g, &mut v, strings);
    }
    g.note("edited spec", &v);
    decode(&compact(&v)).ok()
}

/// A generated subset of the field ids, each in it with probability 1/8.
pub(crate) fn gen_unset(g: &mut Gen) -> BTreeSet<FieldId> {
    field_ids()
        .into_iter()
        .filter(|_| g.weighted(&[7, 1]) == 1)
        .collect()
}

/// `n` as a JSON number with the lexeme `text`.
pub(crate) fn number(text: &str) -> Result<Value, String> {
    Number::from_lexeme(text)
        .map(Value::Number)
        .map_err(|e| format!("{text:?}: {e:?}"))
}
