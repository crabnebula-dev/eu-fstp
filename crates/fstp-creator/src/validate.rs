//! The validation report (M4 design section 3.2, "Validation").
//!
//! [`validate`] is total. It never panics and never answers a check it
//! cannot decide with a pass. A check whose source is missing reports a
//! failure with [`CheckDetail::Unavailable`] or [`CheckDetail::NotChecked`].

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, ProgrammeId, TextRef};
use fstp_domain::policy::{McpBindingActions, PolicyVersion, ValidationWarning};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_guide::FunderProfile;
use fstp_ledger::Seq;
use fstp_money::NonNegAmount;
use fstp_programme::kinds::FlowDownObligation;
use fstp_programme::{FIELDS, Field, FieldId, FieldValue};

use crate::check::{
    CallPackageElement, CheckDetail, CheckId, CheckResult, CheckSubject, Severity, WarningKey,
};
use crate::guide::{GuideScan, guide_facts};
use crate::inputs::{CreatorInputs, PreviewOutcome};
use crate::model::{DraftRevision, Invitee, ReportDigest};
use crate::probe::{ProbeKind, ProbeOutcome};
use crate::state::{CreatorState, Draft};
use crate::theme::{MandatoryElement, TextRole, ThemeMode, meets_aa};

/// The validation report of one draft revision. Only [`validate`] builds
/// one, so a report always comes from the checks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ValidationReport {
    programme: ProgrammeId,
    revision: DraftRevision,
    results: Vec<CheckResult>,
}

impl ValidationReport {
    /// The programme.
    pub fn programme(&self) -> ProgrammeId {
        self.programme
    }

    /// The revision the report was computed at.
    pub fn revision(&self) -> DraftRevision {
        self.revision
    }

    /// Every row, in catalogue order, then by subject.
    pub fn results(&self) -> &[CheckResult] {
        &self.results
    }

    /// The rows of severity Failure.
    pub fn failures(&self) -> impl Iterator<Item = &CheckResult> {
        self.results
            .iter()
            .filter(|r| r.severity == Severity::Failure)
    }

    /// The rows of severity Warning.
    pub fn warnings(&self) -> impl Iterator<Item = &CheckResult> {
        self.results
            .iter()
            .filter(|r| r.severity == Severity::Warning)
    }

    /// Whether the report shows `key` as a warning.
    pub fn shows_warning(&self, key: &WarningKey) -> bool {
        self.warnings()
            .any(|r| r.check == key.check && r.subject == key.subject)
    }

    /// The fingerprint of the report.
    pub fn digest(&self) -> ReportDigest {
        ReportDigest::new(
            self.programme,
            self.revision,
            self.results.iter().map(CheckResult::key).collect(),
        )
    }
}

/// The facts of the funder profile the checks read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfileFacts {
    /// Whether the statements on grant agreement obligations still wait
    /// for approved wording (Q6).
    pub(crate) wording_pending: bool,
    /// Why the wording status is unknown, if it is.
    pub(crate) unknown: Option<&'static str>,
    /// The funder per-recipient ceiling the profile sets, if any.
    pub(crate) ceiling: Option<NonNegAmount>,
}

/// The facts of the draft the content checks read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContentFacts {
    /// The fields with no value (`Compiled::unset` of the draft spec).
    pub(crate) unset: BTreeSet<FieldId>,
    /// Whether the P-57 start lies after its end, or why that is unknown.
    pub(crate) action_dates_reversed: Result<bool, &'static str>,
    /// The I-48 elements the draft lacks.
    pub(crate) call_package_missing: BTreeSet<CallPackageElement>,
    /// The Guide facts (I-51, I-52), or why the Guide checks cannot run.
    pub(crate) guide: Result<GuideScan, &'static str>,
    /// The flow-down obligations the draft lacks (I-49), or why the
    /// draft's list is unknown.
    pub(crate) flow_down_missing: Result<BTreeSet<String>, &'static str>,
    /// Whether P-23 is enabled. An unreadable P-23 counts as enabled.
    pub(crate) precheck_enabled: bool,
}

/// Why the content facts are not available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unavailable(pub(crate) &'static str);

/// The facts a report reads beyond the core, the creator and the inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DraftFacts {
    pub(crate) profile: ProfileFacts,
    pub(crate) content: Result<ContentFacts, Unavailable>,
}

/// The profile checks fail closed without a profile.
const NO_PROFILE_PASSED: &str =
    "no funder profile was passed (fstp_guide::FunderProfile from the cell's profile source)";

/// The flow-down list of a saved value that is not held.
pub(crate) const FLOW_DOWN_NOT_HELD: &str = "the saved flow-down list, which the shell has not held (CreatorState::hold_saved after the save's entry)";

/// The flow-down obligations come from the draft's funder profile.
const FLOW_DOWN_NO_PROFILE: &str =
    "the flow-down obligations of the draft's funder profile, which names no shipped profile";

/// The P-57 value of a set field does not read back from the policy.
const ACTION_DATES_UNREADABLE: &str = "the P-57 value of the draft policy";

/// The profile facts: the wording status of the Guide profile (Q6). The
/// Guide profile sets no per-recipient ceiling, so P-58 of the draft is
/// the only ceiling. Without a profile the wording counts as pending.
pub(crate) fn profile_facts(profile: Option<&FunderProfile>) -> ProfileFacts {
    match profile {
        Some(p) => ProfileFacts {
            wording_pending: p.legal_wording_pending(),
            unknown: None,
            ceiling: None,
        },
        None => ProfileFacts {
            wording_pending: true,
            unknown: Some(NO_PROFILE_PASSED),
            ceiling: None,
        },
    }
}

/// The content facts of the draft of `programme`, over the draft spec: the
/// core head policy, which every start and policy save compiles, the set
/// fields of the draft and the held values (module `draft`), and the
/// Guide API over the draft spec (`fstp_guide::preview`, module `guide`).
pub(crate) fn content_facts(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    profile: Option<&FunderProfile>,
) -> Result<ContentFacts, Unavailable> {
    let draft = creator
        .draft(programme)
        .ok_or(Unavailable("no draft of this programme"))?;
    let head = fstp_domain::policy::head(core, programme)
        .ok_or(Unavailable("the draft has no policy version"))?;
    let set = draft.set_fields();
    let unset: BTreeSet<FieldId> = FIELDS
        .iter()
        .map(|f| f.id)
        .filter(|f| !set.contains(f))
        .collect();
    let policy = fstp_programme::policy_spec(head);
    let action_dates_reversed = if set.contains(&FieldId::P57) {
        match policy.get(FieldId::P57) {
            Field::Set(FieldValue::P57(d)) => Ok(d.start > d.end),
            _ => Err(ACTION_DATES_UNREADABLE),
        }
    } else {
        Ok(false)
    };
    let has = |f: FieldId| set.contains(&f);
    let activities = matches!(
        policy.get(FieldId::P55),
        Field::Set(FieldValue::P55(k)) if !k.items().is_empty()
    );
    let mut call_package_missing = BTreeSet::new();
    for (element, present) in [
        (CallPackageElement::MaximumPerRecipient, has(FieldId::P05)),
        (
            CallPackageElement::ExactAmountCriteria,
            has(FieldId::AmountCriteria),
        ),
        (
            CallPackageElement::ClosedActivityList,
            has(FieldId::P55) && activities,
        ),
        (
            CallPackageElement::PersonsSupported,
            has(FieldId::PersonsSupported),
        ),
        (CallPackageElement::AwardCriteria, has(FieldId::P01)),
        // Interim, pending Daniel: the award procedure is the stage 1
        // threshold, the reviewer minimum and the committee voting rules.
        (
            CallPackageElement::AwardProcedure,
            has(FieldId::P02) && has(FieldId::P03) && has(FieldId::P16),
        ),
    ] {
        if !present {
            call_package_missing.insert(element);
        }
    }
    let precheck_enabled = match policy.get(FieldId::P23) {
        Field::Set(FieldValue::P23(p)) => p.enabled,
        _ => true,
    };
    let guide = guide_facts(creator, programme, draft, head, profile, &set);
    Ok(ContentFacts {
        flow_down_missing: flow_down_missing(creator, programme, draft, has(FieldId::FlowDown)),
        unset,
        action_dates_reversed,
        call_package_missing,
        guide,
        precheck_enabled,
    })
}

/// The obligations of the draft profile's flow-down set (I-49) that the
/// draft's list lacks, by identifier. A gap lacks every obligation. A
/// saved list that is not held is unknown, so the check fails closed.
fn flow_down_missing(
    creator: &CreatorState,
    programme: ProgrammeId,
    draft: &Draft,
    set: bool,
) -> Result<BTreeSet<String>, &'static str> {
    let profile = crate::draft::profile_of(draft).map_err(|_| FLOW_DOWN_NO_PROFILE)?;
    let listed: BTreeSet<FlowDownObligation> = if set {
        match crate::draft::field_value(creator, programme, draft, FieldId::FlowDown) {
            Some(FieldValue::FlowDown(l)) => l.items().iter().copied().collect(),
            _ => return Err(FLOW_DOWN_NOT_HELD),
        }
    } else {
        BTreeSet::new()
    };
    Ok(profile
        .flow_down()
        .iter()
        .filter(|o| !listed.contains(o))
        .map(|o| o.as_str().to_owned())
        .collect())
}

/// The facts of `programme` for a decision or report.
pub(crate) fn draft_facts(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    profile: Option<&FunderProfile>,
) -> DraftFacts {
    DraftFacts {
        profile: profile_facts(profile),
        content: content_facts(core, creator, programme, profile),
    }
}

/// Where a decision reads its draft facts: facts a caller gives, or the
/// draft's own facts, computed when the decision first reads them.
pub(crate) trait ReadFacts {
    /// The facts of the draft of `programme`.
    fn read(
        &self,
        core: &State,
        creator: &CreatorState,
        programme: ProgrammeId,
        profile: Option<&FunderProfile>,
    ) -> Cow<'_, DraftFacts>;
}

impl ReadFacts for DraftFacts {
    fn read(
        &self,
        _: &State,
        _: &CreatorState,
        _: ProgrammeId,
        _: Option<&FunderProfile>,
    ) -> Cow<'_, DraftFacts> {
        Cow::Borrowed(self)
    }
}

/// The draft's own facts ([`draft_facts`]), computed on each read. A
/// decision reads them only after its cheaper guards, so a refused command
/// renders no Guide preview.
pub(crate) struct OwnFacts;

impl ReadFacts for OwnFacts {
    fn read(
        &self,
        core: &State,
        creator: &CreatorState,
        programme: ProgrammeId,
        profile: Option<&FunderProfile>,
    ) -> Cow<'_, DraftFacts> {
        Cow::Owned(draft_facts(core, creator, programme, profile))
    }
}

/// Validates the draft of `programme` (design section 3.2).
///
/// The report binds to the draft's head revision. Probe results, SoD
/// previews and vault answers come from `inputs`. A missing answer fails
/// its check closed.
pub fn validate(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    profile: &FunderProfile,
    inputs: &CreatorInputs,
) -> ValidationReport {
    let facts = draft_facts(core, creator, programme, Some(profile));
    validate_at(core, creator, programme, &facts, inputs)
}

/// The rows of one report, keyed for catalogue order.
struct Rows(BTreeMap<(usize, CheckSubject), CheckResult>);

impl Rows {
    fn push(&mut self, check: CheckId, subject: CheckSubject, detail: CheckDetail) {
        let key = (check.position(), subject.clone());
        self.0.entry(key).or_insert(CheckResult {
            check,
            severity: check.severity(),
            subject,
            detail,
        });
    }
}

/// The report over explicit facts. Crate-private, so no caller outside
/// the crate can feed made-up facts into a report.
pub(crate) fn validate_at(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    facts: &DraftFacts,
    inputs: &CreatorInputs,
) -> ValidationReport {
    let mut rows = Rows(BTreeMap::new());
    let Some(draft) = creator.draft(programme) else {
        rows.push(
            CheckId::PolicyInvalid,
            CheckSubject::Draft,
            CheckDetail::Unavailable("no draft of this programme"),
        );
        return finish(programme, DraftRevision::new(0, Seq::ZERO), rows);
    };
    // Every start and every policy save compiles the draft spec into the
    // core head, so the head is the compiled draft policy (I-51).
    let policy = fstp_domain::policy::head(core, programme);
    policy_rows(&mut rows, policy, &facts.profile);
    content_rows(&mut rows, &facts.content, inputs);
    if facts.profile.wording_pending {
        let detail = match facts.profile.unknown {
            Some(why) => CheckDetail::Unavailable(why),
            None => CheckDetail::None,
        };
        rows.push(CheckId::LegalWordingPending, CheckSubject::Draft, detail);
    }
    invitation_rows(&mut rows, draft, inputs);
    if inputs.tenant_admins.len() < 2 {
        rows.push(
            CheckId::TooFewTenantAdmins,
            CheckSubject::Draft,
            CheckDetail::None,
        );
    }
    builder_rows(&mut rows, draft, inputs);
    if roster_short(core, programme, draft, policy) {
        rows.push(CheckId::RosterShort, CheckSubject::Draft, CheckDetail::None);
    }
    match inputs.vault.exclusion_classes_known {
        Some(true) => {}
        Some(false) => rows.push(
            CheckId::ExclusionClassUnknown,
            CheckSubject::Draft,
            CheckDetail::None,
        ),
        None => rows.push(
            CheckId::ExclusionClassUnknown,
            CheckSubject::Draft,
            CheckDetail::NotChecked,
        ),
    }
    match inputs.vault.proximity_lists_declared {
        Some(true) => {}
        Some(false) => rows.push(
            CheckId::ProximityListMissing,
            CheckSubject::Draft,
            CheckDetail::None,
        ),
        None => rows.push(
            CheckId::ProximityListMissing,
            CheckSubject::Draft,
            CheckDetail::NotChecked,
        ),
    }
    if policy.is_some_and(|v| v.frozen.p77 == McpBindingActions::Allowed)
        && inputs.ports.score_tools
    {
        rows.push(
            CheckId::AiActReassessment,
            CheckSubject::Draft,
            CheckDetail::None,
        );
    }
    for probe in ProbeKind::ALL {
        let outcome = inputs.probes.get(probe);
        if outcome != ProbeOutcome::Pass {
            let check = match probe {
                ProbeKind::Channel => CheckId::ChannelUnreachable,
                ProbeKind::SendingDomain => CheckId::SendingDomainUnverified,
                ProbeKind::Inference => CheckId::InferenceUnreachable,
            };
            rows.push(
                check,
                CheckSubject::Probe(probe),
                CheckDetail::Probe(outcome),
            );
        }
    }
    theme_rows(&mut rows, inputs);
    if inputs.unresolved_imports > 0 {
        rows.push(
            CheckId::ImportUnresolved,
            CheckSubject::Draft,
            CheckDetail::None,
        );
    }
    finish(programme, draft.head(), rows)
}

fn finish(programme: ProgrammeId, revision: DraftRevision, rows: Rows) -> ValidationReport {
    ValidationReport {
        programme,
        revision,
        results: rows.0.into_values().collect(),
    }
}

fn policy_rows(rows: &mut Rows, policy: Option<&PolicyVersion>, profile: &ProfileFacts) {
    let Some(v) = policy else {
        rows.push(
            CheckId::PolicyInvalid,
            CheckSubject::Draft,
            CheckDetail::Unavailable("the draft has no policy version"),
        );
        return;
    };
    match fstp_domain::policy::validate(v) {
        // The cap row below names both values, so I-50 gives no second row.
        Err(r) if r.rule == RuleRef::I50 => {}
        Err(r) => rows.push(
            CheckId::PolicyInvalid,
            CheckSubject::Draft,
            CheckDetail::Rule(r.rule),
        ),
        Ok(warnings) => {
            for w in warnings {
                let check = match w {
                    ValidationWarning::P04MaxAboveP05 => CheckId::P04MaxAboveP05,
                    ValidationWarning::P39AboveP03 => CheckId::P39AboveP03,
                };
                rows.push(check, CheckSubject::Draft, CheckDetail::None);
            }
        }
    }
    let ceiling = v.live.p58.or(profile.ceiling);
    if let Some(c) = ceiling {
        let p05 = v.live.p05.amount();
        let above = p05
            .cmp_same(c.amount())
            .map(|o| o == std::cmp::Ordering::Greater)
            .unwrap_or(true);
        if above {
            rows.push(
                CheckId::CapAboveCeiling,
                CheckSubject::Draft,
                CheckDetail::Cap {
                    p05: p05.to_string(),
                    p58: c.amount().to_string(),
                },
            );
        }
    }
}

/// The checks that read the draft spec. Without a draft or a head policy
/// each fails closed.
const CONTENT_CHECKS: [CheckId; 7] = [
    CheckId::FieldUnset,
    CheckId::ActionDatesInconsistent,
    CheckId::CallPackageIncomplete,
    CheckId::GuideSectionMissing,
    CheckId::GuideBindingUnresolved,
    CheckId::FlowDownMissing,
    CheckId::PrecheckUnavailable,
];

fn content_rows(
    rows: &mut Rows,
    content: &Result<ContentFacts, Unavailable>,
    inputs: &CreatorInputs,
) {
    let c = match content {
        Ok(c) => c,
        Err(Unavailable(why)) => {
            for check in CONTENT_CHECKS {
                rows.push(check, CheckSubject::Draft, CheckDetail::Unavailable(why));
            }
            return;
        }
    };
    for f in &c.unset {
        rows.push(
            CheckId::FieldUnset,
            CheckSubject::Field(*f),
            CheckDetail::None,
        );
    }
    match c.action_dates_reversed {
        Ok(false) => {}
        Ok(true) => rows.push(
            CheckId::ActionDatesInconsistent,
            CheckSubject::Draft,
            CheckDetail::None,
        ),
        Err(why) => rows.push(
            CheckId::ActionDatesInconsistent,
            CheckSubject::Draft,
            CheckDetail::Unavailable(why),
        ),
    }
    for e in &c.call_package_missing {
        rows.push(
            CheckId::CallPackageIncomplete,
            CheckSubject::CallPackage(*e),
            CheckDetail::None,
        );
    }
    match &c.guide {
        Ok(GuideScan {
            sections_missing,
            unresolved,
        }) => {
            for s in sections_missing {
                rows.push(
                    CheckId::GuideSectionMissing,
                    CheckSubject::GuideSection(s.clone()),
                    CheckDetail::None,
                );
            }
            for p in unresolved {
                rows.push(
                    CheckId::GuideBindingUnresolved,
                    CheckSubject::Placeholder(p.clone()),
                    CheckDetail::None,
                );
            }
        }
        Err(why) => {
            for check in [
                CheckId::GuideSectionMissing,
                CheckId::GuideBindingUnresolved,
            ] {
                rows.push(check, CheckSubject::Draft, CheckDetail::Unavailable(why));
            }
        }
    }
    match &c.flow_down_missing {
        Ok(missing) => {
            for o in missing {
                rows.push(
                    CheckId::FlowDownMissing,
                    CheckSubject::FlowDown(o.clone()),
                    CheckDetail::None,
                );
            }
        }
        Err(why) => rows.push(
            CheckId::FlowDownMissing,
            CheckSubject::Draft,
            CheckDetail::Unavailable(why),
        ),
    }
    if c.precheck_enabled && !inputs.ports.precheck {
        rows.push(
            CheckId::PrecheckUnavailable,
            CheckSubject::Draft,
            CheckDetail::None,
        );
    }
}

fn invitation_rows(rows: &mut Rows, draft: &Draft, inputs: &CreatorInputs) {
    for (id, i) in draft.live_invitations() {
        match i.account() {
            Some(_) => match inputs.sod.outcomes.get(&id) {
                Some(PreviewOutcome::Admitted) => {}
                Some(PreviewOutcome::Refused(rule)) => rows.push(
                    CheckId::InviteeRefused,
                    CheckSubject::Invitation(id),
                    CheckDetail::Rule(*rule),
                ),
                None => rows.push(
                    CheckId::InviteeRefused,
                    CheckSubject::Invitation(id),
                    CheckDetail::NotChecked,
                ),
            },
            None => rows.push(
                CheckId::InviteeWithoutAccount,
                CheckSubject::Invitation(id),
                CheckDetail::None,
            ),
        }
    }
}

fn builder_rows(rows: &mut Rows, draft: &Draft, inputs: &CreatorInputs) {
    let mut missing = false;
    let mut unverified = false;
    for b in draft.builders() {
        match inputs.vault.is_verified.get(b) {
            Some(true) => {}
            Some(false) => unverified = true,
            None => missing = true,
        }
    }
    if unverified || missing {
        let detail = if unverified {
            CheckDetail::None
        } else {
            CheckDetail::NotChecked
        };
        rows.push(CheckId::BuilderUnverified, CheckSubject::Draft, detail);
    }
}

/// One person of the roster count: an account, or the contact of a
/// pending invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Person {
    Account(AccountId),
    Contact(TextRef),
}

/// Whether the invited and granted roster is short (no rule in the spec,
/// so a warning). Committee members fewer than P-03, committee
/// organisations fewer than P-39, IRC members fewer than P-15, no chair or
/// no coordinator.
fn roster_short(
    core: &State,
    programme: ProgrammeId,
    draft: &Draft,
    policy: Option<&PolicyVersion>,
) -> bool {
    let Some(v) = policy else {
        return true;
    };
    let mut people: BTreeMap<Role, BTreeSet<Person>> = BTreeMap::new();
    let mut organisations = BTreeSet::new();
    let mut add = |role: Role, who: Person, org| {
        people.entry(role).or_default().insert(who);
        if role == Role::CommitteeMember
            && let Some(o) = org
        {
            organisations.insert(o);
        }
    };
    for (_, i) in draft.live_invitations() {
        let who = match (i.account(), i.invitee) {
            (Some(a), _) => Person::Account(a),
            (None, Invitee::Pending { contact }) => Person::Contact(contact),
            (None, Invitee::Account(a)) => Person::Account(a),
        };
        add(i.role, who, i.organisation);
    }
    for (_, b) in core.roster().bindings() {
        if b.programme == programme && b.held() {
            add(b.role, Person::Account(b.account), b.organisation);
        }
    }
    let count = |role: Role| people.get(&role).map_or(0, BTreeSet::len);
    count(Role::CommitteeMember) < usize::from(v.frozen.p03.get())
        || organisations.len() < usize::from(v.frozen.p39.get())
        || count(Role::IrcMember) < usize::from(v.frozen.p15.get())
        || count(Role::CommitteeChair) == 0
        || count(Role::FstpCoordinator) == 0
}

fn theme_rows(rows: &mut Rows, inputs: &CreatorInputs) {
    let theme = &inputs.theme;
    for e in MandatoryElement::ALL {
        if !theme.elements.contains(&e) {
            rows.push(
                CheckId::MandatoryElementMissing,
                CheckSubject::Element(e),
                CheckDetail::None,
            );
        }
    }
    for mode in [ThemeMode::Light, ThemeMode::Dark] {
        if !theme.pairs.iter().any(|p| p.mode == mode) {
            rows.push(
                CheckId::ContrastFailure,
                CheckSubject::Colour {
                    mode,
                    role: TextRole::Body,
                },
                CheckDetail::NotChecked,
            );
        }
    }
    for p in &theme.pairs {
        if !meets_aa(p.text, p.background) {
            rows.push(
                CheckId::ContrastFailure,
                CheckSubject::Colour {
                    mode: p.mode,
                    role: p.role,
                },
                CheckDetail::None,
            );
        }
    }
}
