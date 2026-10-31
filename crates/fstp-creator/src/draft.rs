//! The draft spec: what the creator knows of each field of a draft, and
//! how a start or a save becomes the next draft policy (M4 design sections
//! 3.1 and 3.2).
//!
//! # Where a field value lives
//!
//! - A policy field lives in the core head policy, which every start and
//!   every policy save replaces through one core `EditPolicy`. So the
//!   head is the compiled draft policy (I-51). The creator reads it back
//!   with [`fstp_programme::policy_spec`].
//! - The ledger body of a save holds the digest of each value, never the
//!   value (ADR-007). The value of a saved field is held outside the
//!   ledger in [`CreatorState`], keyed by that digest, as the import store
//!   holds proposal values. A saved value that is not held is unknown, and
//!   every check that needs it fails closed.
//! - A template start sets the template's values, which ship with the
//!   platform, so they need no holding. Narrative waits for
//!   `AcceptNarrative`: template text is never applied silently.
//!
//! Interim, pending Daniel: a start replaces the whole draft content, a
//! clone copies the source's policy fields only, and an import start
//! begins from the profile defaults while its values arrive as proposals.

use std::collections::BTreeSet;

use fstp_domain::command::Ctx;
use fstp_domain::id::{ContentDigest, PolicyVersionId, ProgrammeId};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::state::{State, UsedId};
use fstp_programme::{
    CompileIds, FIELDS, Field, FieldId, FieldKind, FieldValue, FunderProfile, Narrative,
    ProgrammeSpec, Template, compile,
};

use crate::decide::CreatorRefusal;
use crate::ids::TemplateId;
use crate::model::{DraftRevision, StartingPoint};
use crate::state::{CreatorState, Draft};

/// A draft whose P-53 names no shipped funder profile cannot compile.
pub(crate) const NO_PROFILE: &str = "a funder profile other than horizon-europe version 1, the only fstp_programme::FunderProfile in M4 (design 3.1),";

/// A start from a tenant-private template needs its spec, which the
/// ledger keeps only as a reference (Q17).
pub(crate) const TENANT_TEMPLATE: &str = "ApplyStart from a tenant-private template: the shell's template spec store (design 3.2, R-PG-05; lane W2a seam)";

/// No free policy version id was found near the command id.
pub(crate) const NO_VERSION: &str =
    "a free policy version id within 64 of the command id (design 3.2)";

/// How many ids after the command id [`fresh_version`] tries.
const VERSION_TRIES: u128 = 64;

/// The shipped funder profile the draft's P-53 names.
pub(crate) fn profile_of(draft: &Draft) -> Result<FunderProfile, CreatorRefusal> {
    FunderProfile::for_policy_ref(draft.profile()).ok_or(CreatorRefusal::Unavailable(NO_PROFILE))
}

/// The kind of `field`.
pub(crate) fn kind(field: FieldId) -> Option<FieldKind> {
    field.spec().map(|s| s.kind)
}

/// The shipped template `template` at `version`, if one ships.
pub(crate) fn shipped_template(template: TemplateId, version: u32) -> Option<Template> {
    fstp_programme::shipped_templates()
        .ok()?
        .into_iter()
        .find(|t| t.id.raw() == template.raw() && t.version.get() == version)
}

/// Whether `template` names a shipped template at any version, so a
/// tenant-private template cannot take its id.
pub(crate) fn is_shipped(template: TemplateId) -> bool {
    fstp_programme::shipped_templates()
        .map(|ts| ts.iter().any(|t| t.id.raw() == template.raw()))
        .unwrap_or(true)
}

/// Whether a template value waits for `AcceptNarrative` instead of being
/// applied by the start: an artefact field of narrative text, or P-09
/// whose wording is still inline (ADR-007 keeps inline text out of a
/// ledger body). Interim, pending Daniel.
pub(crate) fn needs_acceptance(value: &FieldValue) -> bool {
    match value {
        FieldValue::ActionAcronym(_)
        | FieldValue::CoordinatorName(_)
        | FieldValue::ProgrammeName(_)
        | FieldValue::ProgrammeNarrative(_)
        | FieldValue::ProgrammeScope(_)
        | FieldValue::PersonsSupported(_)
        | FieldValue::Minors(_)
        | FieldValue::AmountCriteria(_)
        | FieldValue::Faq(_)
        | FieldValue::ProgrammeContact(_)
        | FieldValue::MessageTemplates(_) => true,
        FieldValue::P09(k) => k
            .items()
            .iter()
            .any(|x| matches!(x.text, Narrative::Inline(_))),
        _ => false,
    }
}

/// The part of a template spec a start applies: every value but those
/// that wait for acceptance.
pub(crate) fn applied(spec: &ProgrammeSpec) -> ProgrammeSpec {
    let mut out = spec.clone();
    for f in FIELDS {
        if let Field::Set(v) = spec.get(f.id)
            && needs_acceptance(&v)
        {
            out.unset(f.id);
        }
    }
    out
}

/// The fields `spec` sets.
fn set_in(spec: &ProgrammeSpec) -> BTreeSet<FieldId> {
    FIELDS
        .iter()
        .map(|f| f.id)
        .filter(|f| spec.get(*f).is_set())
        .collect()
}

/// The fields a start sets, as the fold records them on `StartApplied`.
/// P-53 is always set and is not listed.
///
/// A clone sets the policy fields the source draft set, or every policy
/// field of a programme that has no creator draft. Interim, pending
/// Daniel: a clone copies no artefact field.
pub(crate) fn start_fields(creator: &CreatorState, start: &StartingPoint) -> BTreeSet<FieldId> {
    match start {
        StartingPoint::Blank { .. } | StartingPoint::Import { .. } => BTreeSet::new(),
        StartingPoint::Template { template, version } => shipped_template(*template, *version)
            .map(|t| set_in(&applied(&t.spec)))
            .unwrap_or_default(),
        StartingPoint::Clone { source } => {
            let policy = |f: &FieldId| kind(*f) == Some(FieldKind::Policy);
            match creator.draft(*source) {
                Some(d) => d.set_fields().into_iter().filter(policy).collect(),
                None => FIELDS.iter().map(|f| f.id).filter(policy).collect(),
            }
        }
    }
    .into_iter()
    .filter(|f| *f != FieldId::P53)
    .collect()
}

/// The value of `field` in the draft of `programme`, if the creator holds
/// it: the held value of a saved field, or the template value of a field
/// the start set or the programme manager accepted. `None` for a gap and
/// for a saved value that is not held.
pub(crate) fn field_value(
    creator: &CreatorState,
    programme: ProgrammeId,
    draft: &Draft,
    field: FieldId,
) -> Option<FieldValue> {
    if let Some((digest, _)) = draft.fields().get(&field) {
        return creator.held(programme, field, *digest).cloned();
    }
    if !draft.start_fields().contains(&field) && !draft.narratives().contains(&field) {
        return None;
    }
    match draft.start() {
        Some(StartingPoint::Template { template, version }) => {
            shipped_template(*template, *version)?
                .spec
                .get(field)
                .as_set()
                .cloned()
        }
        _ => None,
    }
}

/// A policy version id no version of the cell holds: the command id read
/// as an integer, or the first free id after it. The shell draws the
/// command id, so the id is deterministic per command. Interim, pending
/// Daniel: the creator commands carry no version id.
pub(crate) fn fresh_version(core: &State, ctx: &Ctx) -> Result<PolicyVersionId, CreatorRefusal> {
    let start = u128::from_be_bytes(ctx.command.bytes());
    (0..VERSION_TRIES)
        .map(|i| PolicyVersionId::from_raw(start.wrapping_add(i)))
        .find(|v| !core.used_ids().contains(UsedId::PolicyVersion(*v)))
        .ok_or(CreatorRefusal::Unavailable(NO_VERSION))
}

/// Compiles `spec` as the next version of `head` and checks that it can go
/// into a ledger body. A spec that does not compile under the profile, or
/// whose P-09 wording is still inline (ADR-007), is refused as an invalid
/// save.
fn next_version(
    spec: &ProgrammeSpec,
    profile: &FunderProfile,
    head: &PolicyVersion,
    version: PolicyVersionId,
) -> Result<PolicyVersion, CreatorRefusal> {
    let compiled = compile(
        spec,
        profile,
        CompileIds::new(head.programme, version, Some(head.id)),
    )
    .map_err(|_| CreatorRefusal::NothingToSave)?;
    if !compiled.ledger_ready() {
        return Err(CreatorRefusal::NothingToSave);
    }
    Ok(compiled.policy)
}

/// The head policy with the policy values of a save, compiled as the next
/// version (design 3.2 "How a save becomes policy"). Every parameter the
/// save does not touch keeps its head value.
pub(crate) fn edited_policy(
    head: &PolicyVersion,
    profile: &FunderProfile,
    values: &[&FieldValue],
    version: PolicyVersionId,
) -> Result<PolicyVersion, CreatorRefusal> {
    let mut spec = fstp_programme::policy_spec(head);
    for v in values {
        spec.set((*v).clone());
    }
    next_version(&spec, profile, head, version)
}

/// The policy a start writes as the next version of `head`.
pub(crate) fn start_policy(
    core: &State,
    creator: &CreatorState,
    draft: &Draft,
    head: &PolicyVersion,
    start: &StartingPoint,
    version: PolicyVersionId,
) -> Result<PolicyVersion, CreatorRefusal> {
    let profile = profile_of(draft)?;
    match start {
        StartingPoint::Blank { profile: named } => {
            if named != draft.profile() {
                return Err(CreatorRefusal::NothingToSave);
            }
            next_version(&profile.blank(), &profile, head, version)
        }
        StartingPoint::Import { .. } => next_version(&profile.blank(), &profile, head, version),
        StartingPoint::Template {
            template,
            version: v,
        } => {
            let Some(t) = shipped_template(*template, *v) else {
                if creator.template_taken(*template) {
                    return Err(CreatorRefusal::Unavailable(TENANT_TEMPLATE));
                }
                return Err(CreatorRefusal::UnknownSource);
            };
            if t.profile != profile.reference() {
                return Err(CreatorRefusal::NothingToSave);
            }
            next_version(&applied(&t.spec), &profile, head, version)
        }
        StartingPoint::Clone { source } => {
            let s =
                fstp_domain::policy::head(core, *source).ok_or(CreatorRefusal::UnknownSource)?;
            if s.currency != head.currency || s.frozen.p53 != head.frozen.p53 {
                return Err(CreatorRefusal::NothingToSave);
            }
            Ok(PolicyVersion {
                id: version,
                programme: head.programme,
                parent: Some(head.id),
                ..s.clone()
            })
        }
    }
}

/// The reference a `TemplateSaved` record keeps for the template spec:
/// the programme and the draft revision the spec was saved at, packed in
/// order into the 32 bytes. Interim, pending Daniel: the pure crates
/// compute no hashes, so this is a reference, not a digest. In one cell
/// ledger the revision pins the spec, and the shell's template store maps
/// the reference to the spec text.
pub(crate) fn spec_ref(programme: ProgrammeId, revision: DraftRevision) -> ContentDigest {
    let mut b = [0u8; 32];
    let parts: [&[u8]; 3] = [
        &programme.raw().to_be_bytes(),
        &revision.seq().to_be_bytes(),
        &revision.entry().raw().to_be_bytes(),
    ];
    for (slot, byte) in b.iter_mut().zip(parts.into_iter().flatten()) {
        *slot = *byte;
    }
    ContentDigest::from_bytes(b)
}
