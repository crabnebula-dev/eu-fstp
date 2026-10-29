//! `compile` and `decompile` (M4 design section 3.1).
//!
//! - `compile` is a pure function of the spec, the funder profile and the
//!   shell-supplied ids. It sets every programme-level `CATALOGUE` entry and
//!   nothing else. Typed parameters go to their `PolicyVersion` field, and
//!   every other one to the opaque map its freeze flag selects (I-12).
//! - A gap compiles to the profile's placeholder and is listed in
//!   [`Compiled::unset`]. P-56 and P-58 are optional in the policy, so their
//!   gap is `None`.
//! - Free text never enters the policy (ADR-007). P-01 names, P-09
//!   wording, P-13 descriptions and P-55 names go to the
//!   [`ProgrammeArtefacts`]. The policy keeps their ids, and P-09 keeps the
//!   wording's `TextRef`, or [`INLINE_TEXT`] while the wording is inline.
//! - `decompile` reads every field back. On what `compile` returned it is
//!   the exact inverse. A field it cannot read back consistently decompiles
//!   as a gap, so `decompile` is total.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{
    ActivityTypeId, ClassId, CriterionId, KnockOutCriterionId, PolicyVersionId, ProgrammeId,
};
use fstp_domain::policy as dp;
use fstp_domain::policy::{
    FrozenValues, LiveValues, OpaqueValue, PolicyVersion, is_frozen_opaque, is_live_opaque,
};
use fstp_domain::rules::ParamId;
use fstp_domain::scoring::{Criteria, Criterion};
use fstp_json::Value;
use fstp_money::Currency;

use crate::kinds::{
    ActivityType, ExclusionClass, Inference, Keyed, KnockOut, NamedCriterion, ProximityEntry,
    ProximityLists, ScoringCriteria,
};
use crate::profile::FunderProfile;
use crate::spec::{FIELDS, Field, FieldId, FieldKind, FieldValue, ProgrammeSpec, canonical};
use crate::value::{
    Codec, INLINE_TEXT, Licence, ModelName, Narrative, ReviewerMinimum, SortedSet, Token,
    UniqueList,
};

/// The ids the shell supplies for one compiled policy version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CompileIds {
    /// The programme.
    pub programme: ProgrammeId,
    /// The new policy version.
    pub version: PolicyVersionId,
    /// The version it replaces, `None` for the first.
    pub parent: Option<PolicyVersionId>,
}

impl CompileIds {
    /// The ids of version `version` of `programme`, replacing `parent`.
    pub const fn new(
        programme: ProgrammeId,
        version: PolicyVersionId,
        parent: Option<PolicyVersionId>,
    ) -> CompileIds {
        CompileIds {
            programme,
            version,
            parent,
        }
    }
}

/// Everything of a spec that is not policy: the artefact fields, and the
/// free text of policy fields, keyed by the ids the policy holds.
///
/// Only [`compile`] builds a value, and it has no codec of its own. The
/// creator persists each field value in its strict form
/// ([`crate::encode_field_value`]), and `FieldsSaved` records its digest
/// (M4 design section 3.2). A reader rebuilds the spec from those values
/// and compiles it to get the artefacts. [`decompile`] therefore serves
/// round-trip checks and readers that hold a [`Compiled`]. Interim,
/// pending Daniel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProgrammeArtefacts {
    values: BTreeMap<FieldId, FieldValue>,
    criterion_names: Vec<(CriterionId, Narrative)>,
    knock_out_texts: Vec<(KnockOutCriterionId, Narrative)>,
    class_descriptions: Vec<(ClassId, Narrative)>,
    activity_names: Vec<(ActivityTypeId, Narrative)>,
}

impl ProgrammeArtefacts {
    /// The value of the artefact field `field`, if set.
    pub fn value(&self, field: FieldId) -> Option<&FieldValue> {
        self.values.get(&field)
    }

    /// The P-01 criterion names, in P-01 order.
    pub fn criterion_names(&self) -> &[(CriterionId, Narrative)] {
        &self.criterion_names
    }

    /// The P-09 knock-out wording, in P-09 order.
    pub fn knock_out_texts(&self) -> &[(KnockOutCriterionId, Narrative)] {
        &self.knock_out_texts
    }

    /// The P-13 class descriptions, in the spec's order.
    pub fn class_descriptions(&self) -> &[(ClassId, Narrative)] {
        &self.class_descriptions
    }

    /// The P-55 activity type names, in P-55 order.
    pub fn activity_names(&self) -> &[(ActivityTypeId, Narrative)] {
        &self.activity_names
    }

    /// Keeps the free text of a set policy field.
    fn keep_texts(&mut self, v: &FieldValue) {
        match v {
            FieldValue::P01(c) => {
                self.criterion_names = c
                    .criteria()
                    .iter()
                    .map(|x| (x.id, x.name.clone()))
                    .collect();
            }
            FieldValue::P09(k) => {
                self.knock_out_texts = k.items().iter().map(|x| (x.id, x.text.clone())).collect();
            }
            FieldValue::P13(k) => {
                self.class_descriptions = k
                    .items()
                    .iter()
                    .map(|x| (x.id, x.description.clone()))
                    .collect();
            }
            FieldValue::P55(k) => {
                self.activity_names = k.items().iter().map(|x| (x.id, x.name.clone())).collect();
            }
            _ => {}
        }
    }
}

/// The output of [`compile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    /// The M2 policy version. Gaps hold the profile's placeholders.
    pub policy: PolicyVersion,
    /// The programme artefacts.
    pub artefacts: ProgrammeArtefacts,
    /// The fields with no value. Each is a `FieldUnset` failure.
    pub unset: BTreeSet<FieldId>,
}

impl Compiled {
    /// Whether the policy can go into a ledger body as it is: false while
    /// any P-09 wording is still inline, so P-09 holds [`INLINE_TEXT`].
    /// The creator stores such wording as a `TextRef` first (ADR-007).
    pub fn ledger_ready(&self) -> bool {
        self.policy
            .frozen
            .p09
            .0
            .iter()
            .all(|k| k.text != INLINE_TEXT)
    }
}

/// Why [`compile`] refused a spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompileError {
    /// The spec's currency is not the profile's.
    CurrencyNotInProfile,
    /// The spec's P-53 names another profile than the one compiling it.
    ProfileMismatch,
    /// The field holds no placeholder for a gap under this profile.
    NoPlaceholder(FieldId),
    /// The field's value does not fit the policy. Decoding prevents this,
    /// so it signals a value built outside the decoders.
    Invalid(FieldId),
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CompileError::CurrencyNotInProfile => f.write_str("the currency is not the profile's"),
            CompileError::ProfileMismatch => f.write_str("P-53 names another funder profile"),
            CompileError::NoPlaceholder(id) => write!(f, "no placeholder for {id:?}"),
            CompileError::Invalid(id) => write!(f, "{id:?} does not fit the policy"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Compiles a spec into an M2 policy version and the programme artefacts.
/// Pure and deterministic. Fuzzed (`spec_compile`).
pub fn compile(
    spec: &ProgrammeSpec,
    profile: &FunderProfile,
    ids: CompileIds,
) -> Result<Compiled, CompileError> {
    if spec.currency != profile.currency() {
        return Err(CompileError::CurrencyNotInProfile);
    }
    if let Field::Set(p) = &spec.funder.p53_funder_profile
        && *p != profile.reference()
    {
        return Err(CompileError::ProfileMismatch);
    }
    let mut unset = BTreeSet::new();
    let mut values = BTreeMap::new();
    let mut artefacts = ProgrammeArtefacts::default();
    for f in FIELDS {
        match (f.kind, spec.get(f.id)) {
            (FieldKind::Artefact, Field::Set(v)) => {
                artefacts.values.insert(f.id, v);
            }
            (FieldKind::Artefact, Field::Unset) => {
                unset.insert(f.id);
            }
            (FieldKind::Policy, Field::Set(v)) => {
                artefacts.keep_texts(&v);
                values.insert(f.id, v);
            }
            (FieldKind::Policy, Field::Unset) => {
                unset.insert(f.id);
                let v = profile
                    .placeholder(f.id, spec.currency)
                    .ok_or(CompileError::NoPlaceholder(f.id))?;
                values.insert(f.id, v);
            }
        }
    }
    let policy = build_policy(&values, &unset, spec.currency, ids)?;
    Ok(Compiled {
        policy,
        artefacts,
        unset,
    })
}

/// The value of policy field `$id` in `$values`, or `Invalid`.
macro_rules! take {
    ($values:expr, $id:ident) => {
        match $values.get(&FieldId::$id) {
            Some(FieldValue::$id(x)) => x,
            _ => return Err(CompileError::Invalid(FieldId::$id)),
        }
    };
}

/// The canonical opaque text of `v`.
fn opaque(v: &Value, field: FieldId) -> Result<OpaqueValue, CompileError> {
    OpaqueValue::from_value(v).map_err(|_| CompileError::Invalid(field))
}

/// The JSON a policy keeps for the opaque field value `v`. P-55 keeps
/// only its ids; every other value keeps its full encoding.
fn opaque_json(v: &FieldValue) -> Value {
    match v {
        FieldValue::P55(k) => Value::from(
            k.items()
                .iter()
                .map(|a| crate::value::encode_id(a.id.raw()))
                .collect::<Vec<Value>>(),
        ),
        other => other.to_json(),
    }
}

/// The single parameter a policy field sets.
fn param_of(field: FieldId) -> Option<ParamId> {
    match field.spec().map(|s| s.params) {
        Some([p]) => Some(*p),
        _ => None,
    }
}

fn build_policy(
    values: &BTreeMap<FieldId, FieldValue>,
    unset: &BTreeSet<FieldId>,
    currency: Currency,
    ids: CompileIds,
) -> Result<PolicyVersion, CompileError> {
    let mut frozen_opaque = BTreeMap::new();
    let mut live_opaque = BTreeMap::new();
    for (field, v) in values {
        let Some(p) = param_of(*field) else {
            return Err(CompileError::Invalid(*field));
        };
        if is_frozen_opaque(p) {
            frozen_opaque.insert(p, opaque(&opaque_json(v), *field)?);
        } else if is_live_opaque(p) {
            live_opaque.insert(p, opaque(&opaque_json(v), *field)?);
        }
    }

    let p01 = take!(values, P01);
    let p01 = Criteria::new(
        p01.scale_max(),
        p01.criteria()
            .iter()
            .map(|c| Criterion {
                id: c.id,
                weight: c.weight,
            })
            .collect(),
    )
    .map_err(|_| CompileError::Invalid(FieldId::P01))?;
    let p09 = dp::KnockOutCriteria(
        take!(values, P09)
            .items()
            .iter()
            .map(|k| dp::KnockOutCriterion {
                id: k.id,
                text: k.text.policy_ref(),
            })
            .collect(),
    );
    let p21 = take!(values, P21);
    let p21 = dp::InferenceBinding {
        provider: opaque(&p21.provider.encode(), FieldId::P21)?,
        primary: dp::ModelRef(p21.primary.as_str().to_owned()),
        fallbacks: p21
            .fallbacks
            .items()
            .iter()
            .map(|m| dp::ModelRef(m.as_str().to_owned()))
            .collect(),
    };
    let frozen = FrozenValues {
        p01,
        p02: *take!(values, P02),
        p03: take!(values, P03).get(),
        p04: *take!(values, P04),
        p07: *take!(values, P07),
        p09,
        p10: *take!(values, P10),
        p11: *take!(values, P11),
        p14: dp::IrcExemptions(opaque(&take!(values, P14).encode(), FieldId::P14)?),
        p15: *take!(values, P15),
        p16: dp::VotingRules(opaque(&take!(values, P16).encode(), FieldId::P16)?),
        p17: dp::TieBreakRule(opaque(&take!(values, P17).encode(), FieldId::P17)?),
        p21,
        p24: *take!(values, P24),
        p26: dp::LicenceSet(
            take!(values, P26)
                .items()
                .iter()
                .map(|l| dp::SpdxId(l.as_str().to_owned()))
                .collect(),
        ),
        p39: *take!(values, P39),
        p53: dp::FunderProfileRef(opaque(&take!(values, P53).encode(), FieldId::P53)?),
        p77: *take!(values, P77),
        opaque: frozen_opaque,
    };
    let optional =
        |field: FieldId, v: fstp_money::NonNegAmount| (!unset.contains(&field)).then_some(v);
    let live = LiveValues {
        p05: *take!(values, P05),
        p12: *take!(values, P12),
        p13: dp::ExclusionClasses(take!(values, P13).items().iter().map(|c| c.id).collect()),
        p38: dp::ProximityLists(
            take!(values, P38)
                .entries()
                .iter()
                .map(|e| (e.organisation, e.list))
                .collect(),
        ),
        p56: optional(FieldId::P56, *take!(values, P56)),
        p58: optional(FieldId::P58, *take!(values, P58)),
        opaque: live_opaque,
    };
    Ok(PolicyVersion {
        id: ids.version,
        programme: ids.programme,
        parent: ids.parent,
        currency,
        frozen,
        live,
    })
}

// ---------------------------------------------------------------------------
// decompile
// ---------------------------------------------------------------------------

/// The spec that `compile` turned into `policy` and `artefacts`, with the
/// fields in `unset` as gaps. Total: a field that does not read back
/// consistently becomes a gap.
pub fn decompile(
    policy: &PolicyVersion,
    artefacts: &ProgrammeArtefacts,
    unset: &BTreeSet<FieldId>,
) -> ProgrammeSpec {
    let mut spec = ProgrammeSpec::empty(policy.currency);
    for f in FIELDS {
        if unset.contains(&f.id) {
            continue;
        }
        let v = match f.kind {
            FieldKind::Artefact => artefacts.values.get(&f.id).cloned(),
            FieldKind::Policy => read(f.id, policy, artefacts),
        };
        if let Some(v) = v.filter(|v| v.field() == f.id) {
            spec.set(v);
        }
    }
    spec
}

/// The parsed JSON of an opaque value.
fn parse(o: &OpaqueValue) -> Option<Value> {
    fstp_json::parse_str(o.as_str()).ok()
}

/// Decodes `T` from an opaque value.
fn from_opaque<T: Codec>(o: &OpaqueValue, c: Currency) -> Option<T> {
    T::decode(&parse(o)?, c).ok()
}

/// Rebuilds a keyed list from the policy's ids and the artefacts' texts.
/// The ids must agree in order.
fn rejoin<I: PartialEq + Copy, T>(
    ids: impl ExactSizeIterator<Item = I>,
    texts: &[(I, Narrative)],
    make: impl Fn(I, Narrative) -> T,
) -> Option<Vec<T>> {
    if ids.len() != texts.len() {
        return None;
    }
    ids.zip(texts)
        .map(|(id, (tid, text))| (id == *tid).then(|| make(id, text.clone())))
        .collect()
}

/// Reads one policy field back from `policy` and `artefacts`.
fn read(
    field: FieldId,
    policy: &PolicyVersion,
    artefacts: &ProgrammeArtefacts,
) -> Option<FieldValue> {
    let f = &policy.frozen;
    let l = &policy.live;
    let c = policy.currency;
    let v = match field {
        FieldId::P01 => {
            let items = f.p01.items();
            let criteria = rejoin(
                items.iter().map(|i| i.id),
                &artefacts.criterion_names,
                |id, name| (id, name),
            )?
            .into_iter()
            .zip(items)
            .map(|((id, name), i)| NamedCriterion {
                id,
                name,
                weight: i.weight,
            })
            .collect();
            FieldValue::P01(ScoringCriteria::new(f.p01.scale_max(), criteria)?)
        }
        FieldId::P02 => FieldValue::P02(f.p02),
        FieldId::P03 => FieldValue::P03(ReviewerMinimum::new(f.p03.get())?),
        FieldId::P04 => FieldValue::P04(f.p04),
        FieldId::P07 => FieldValue::P07(f.p07),
        FieldId::P09 => {
            let items = rejoin(
                f.p09.0.iter().map(|k| k.id),
                &artefacts.knock_out_texts,
                |id, text| KnockOut { id, text },
            )?;
            let consistent = items
                .iter()
                .zip(&f.p09.0)
                .all(|(k, p)| k.text.policy_ref() == p.text);
            if !consistent {
                return None;
            }
            FieldValue::P09(Keyed::new(items)?)
        }
        FieldId::P10 => FieldValue::P10(f.p10),
        FieldId::P11 => FieldValue::P11(f.p11),
        FieldId::P14 => FieldValue::P14(from_opaque(&f.p14.0, c)?),
        FieldId::P15 => FieldValue::P15(f.p15),
        FieldId::P16 => FieldValue::P16(from_opaque(&f.p16.0, c)?),
        FieldId::P17 => FieldValue::P17(from_opaque(&f.p17.0, c)?),
        FieldId::P21 => {
            let fallbacks = f
                .p21
                .fallbacks
                .iter()
                .map(|m| ModelName::new(&m.0))
                .collect::<Option<Vec<_>>>()?;
            FieldValue::P21(Inference {
                provider: from_opaque::<Token>(&f.p21.provider, c)?,
                primary: ModelName::new(&f.p21.primary.0)?,
                fallbacks: UniqueList::new(fallbacks)?,
            })
        }
        FieldId::P24 => FieldValue::P24(f.p24),
        FieldId::P26 => {
            let items = f
                .p26
                .0
                .iter()
                .map(|s| Licence::new(&s.0))
                .collect::<Option<Vec<_>>>()?;
            FieldValue::P26(SortedSet::new(items)?)
        }
        FieldId::P39 => FieldValue::P39(f.p39),
        FieldId::P53 => FieldValue::P53(from_opaque(&f.p53.0, c)?),
        FieldId::P77 => FieldValue::P77(f.p77),
        FieldId::P05 => FieldValue::P05(l.p05),
        FieldId::P12 => FieldValue::P12(l.p12),
        FieldId::P13 => {
            let texts = &artefacts.class_descriptions;
            let ids: BTreeSet<ClassId> = texts.iter().map(|(id, _)| *id).collect();
            if ids != l.p13.0 || ids.len() != texts.len() {
                return None;
            }
            let items = texts
                .iter()
                .map(|(id, description)| ExclusionClass {
                    id: *id,
                    description: description.clone(),
                })
                .collect();
            FieldValue::P13(Keyed::new(items)?)
        }
        FieldId::P38 => FieldValue::P38(ProximityLists::new(
            l.p38
                .0
                .iter()
                .map(|(organisation, list)| ProximityEntry {
                    organisation: *organisation,
                    list: *list,
                })
                .collect(),
        )?),
        FieldId::P56 => FieldValue::P56(l.p56?),
        FieldId::P58 => FieldValue::P58(l.p58?),
        FieldId::P55 => {
            let ids = parse(f.opaque.get(&ParamId::P55)?)?;
            let ids = ids
                .as_array()?
                .iter()
                .map(|v| {
                    crate::value::decode_id(v)
                        .ok()
                        .map(ActivityTypeId::from_raw)
                })
                .collect::<Option<Vec<_>>>()?;
            let items = rejoin(ids.into_iter(), &artefacts.activity_names, |id, name| {
                ActivityType { id, name }
            })?;
            FieldValue::P55(Keyed::new(items)?)
        }
        other => {
            let p = param_of(other)?;
            let o = if is_frozen_opaque(p) {
                f.opaque.get(&p)?
            } else if is_live_opaque(p) {
                l.opaque.get(&p)?
            } else {
                return None;
            };
            FieldValue::decode(other, &parse(o)?, c).ok()?
        }
    };
    Some(v)
}

/// The canonical text a policy keeps for an opaque parameter value.
/// Exposed for readers, such as the Guide resolvers, that compare it.
pub fn opaque_text(value: &FieldValue) -> String {
    canonical(&opaque_json(value))
}
