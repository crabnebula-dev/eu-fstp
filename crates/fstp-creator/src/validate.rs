//! The validation report (M4 design section 3.2, "Validation").
//!
//! [`validate`] is total. It never panics and never answers a check it
//! cannot decide with a pass. A check whose source is missing reports a
//! failure with [`CheckDetail::Unavailable`] or [`CheckDetail::NotChecked`].

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, ProgrammeId, TextRef};
use fstp_domain::policy::{McpBindingActions, PolicyVersion, ValidationWarning};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_guide::FunderProfile;
use fstp_ledger::Seq;
use fstp_money::NonNegAmount;
use fstp_programme::FieldId;

use crate::check::{
    CallPackageElement, CheckDetail, CheckId, CheckResult, CheckSubject, Severity, WarningKey,
};
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

/// The facts of the compiled draft the content checks read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContentFacts {
    /// The compiled draft policy, which may differ from the core head.
    pub(crate) compiled: Option<PolicyVersion>,
    /// `Compiled::unset`.
    pub(crate) unset: BTreeSet<FieldId>,
    /// The P-57 action start and end.
    pub(crate) action_dates: Option<(Timestamp, Timestamp)>,
    /// The I-48 elements the draft lacks.
    pub(crate) call_package_missing: BTreeSet<CallPackageElement>,
    /// The required Guide sections the preview lacks (I-52).
    pub(crate) guide_sections_missing: BTreeSet<String>,
    /// The Guide placeholders that do not resolve (I-51).
    pub(crate) guide_bindings_unresolved: BTreeSet<String>,
    /// The flow-down obligations the draft lacks (I-49).
    pub(crate) flow_down_missing: BTreeSet<String>,
    /// Whether P-23 is enabled.
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

/// The source of the content checks while `fstp-programme` and
/// `fstp-guide` are W0 stubs.
pub(crate) const CONTENT_SEAM: &str = "fstp_programme::compile over the draft spec and fstp_guide::preview (design 3.1 and 3.2; lanes W1a and W2c)";

/// The source of the profile checks while `fstp_guide::FunderProfile` is a
/// W0 stub.
pub(crate) const PROFILE_SEAM: &str =
    "the wording status of fstp_guide::FunderProfile (design 3.10; lane W2c)";

/// The profile facts. `fstp_guide::FunderProfile` exposes no wording
/// status or ceiling yet (lane W2c), so the wording counts as pending and
/// no profile ceiling applies. Both fail closed.
pub(crate) fn profile_facts(profile: Option<&FunderProfile>) -> ProfileFacts {
    let _ = profile;
    ProfileFacts {
        wording_pending: true,
        unknown: Some(PROFILE_SEAM),
        ceiling: None,
    }
}

/// The content facts of the draft. `fstp-programme` has no `compile` over
/// a draft spec and `fstp-guide` no preview yet (lanes W1a and W2c), so
/// the facts are unavailable and every content check fails closed.
pub(crate) fn content_facts(
    core: &State,
    creator: &CreatorState,
    programme: ProgrammeId,
    profile: Option<&FunderProfile>,
) -> Result<ContentFacts, Unavailable> {
    let _ = (core, creator, programme, profile);
    Err(Unavailable(CONTENT_SEAM))
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
    let head = fstp_domain::policy::head(core, programme);
    let policy = match &facts.content {
        Ok(ContentFacts {
            compiled: Some(v), ..
        }) => Some(v),
        _ => head,
    };
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

/// The checks that read the compiled draft.
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
    if let Some((start, end)) = c.action_dates
        && start > end
    {
        rows.push(
            CheckId::ActionDatesInconsistent,
            CheckSubject::Draft,
            CheckDetail::None,
        );
    }
    for e in &c.call_package_missing {
        rows.push(
            CheckId::CallPackageIncomplete,
            CheckSubject::CallPackage(*e),
            CheckDetail::None,
        );
    }
    for s in &c.guide_sections_missing {
        rows.push(
            CheckId::GuideSectionMissing,
            CheckSubject::GuideSection(s.clone()),
            CheckDetail::None,
        );
    }
    for p in &c.guide_bindings_unresolved {
        rows.push(
            CheckId::GuideBindingUnresolved,
            CheckSubject::Placeholder(p.clone()),
            CheckDetail::None,
        );
    }
    for o in &c.flow_down_missing {
        rows.push(
            CheckId::FlowDownMissing,
            CheckSubject::FlowDown(o.clone()),
            CheckDetail::None,
        );
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
