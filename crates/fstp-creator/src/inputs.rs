//! What the engine passes in, so the creator never sees the import store,
//! the vault or the tenant projection (M4 design section 3.2,
//! `CreatorInputs`).
//!
//! Every answer the creator needs is a field here. A missing answer is
//! never read as a pass: each check that needs it fails closed.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, OrganisationId, ProgrammeId};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_guide::FunderProfile;

use crate::ids::InvitationId;
use crate::probe::ProbeSet;
use crate::state::CreatorState;
use crate::theme::Theme;

/// The outcome of `fstp_domain::roles::preview_grant` for one invitation:
/// the `GrantRole` SoD guards without the Draft gate (D3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PreviewOutcome {
    /// The guards admit the grant.
    Admitted,
    /// The guards refuse it. Only the rule is kept (R-CF-03).
    Refused(RuleRef),
}

/// The live SoD previews of the draft's invitations with an account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SodPreview {
    /// The outcome per invitation. An invitation with an account and no
    /// outcome fails closed as `InviteeRefused`.
    pub outcomes: BTreeMap<InvitationId, PreviewOutcome>,
}

/// The vault answers the creator reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VaultChecks {
    /// `IsVerified` per asked account.
    pub is_verified: BTreeMap<AccountId, bool>,
    /// `SameIdentityAsAny(account, builders)` per asked account, against
    /// the builder set of [`vault_questions`].
    pub same_identity: BTreeMap<AccountId, bool>,
    /// Whether the vault knows every P-13 class id (Q35). `None` when the
    /// vault gave no answer, which fails closed.
    pub exclusion_classes_known: Option<bool>,
    /// Whether every partner organisation has a declared P-38 list (Q35).
    /// `None` when the vault gave no answer, which reports the warning.
    pub proximity_lists_declared: Option<bool>,
}

/// Which ports exist in the cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PortPresence {
    /// A P-23 pre-check provider (`Precheck` port, M7).
    pub precheck: bool,
    /// Score tools for agents (`ai-act.md` reassessment trigger).
    pub score_tools: bool,
}

/// What the engine passes in for one creator decision or report.
///
/// Interim, pending Daniel: the design lists `unresolved_imports`,
/// `probes`, `sod` and `vault`. The creator also needs the tenant admin
/// set (SoD-07, from `fstp-tenant`), the ports present, the theme and the
/// draft's funder profile, so the engine passes them here too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorInputs {
    /// The count of unresolved import proposals on the draft (Q30).
    pub unresolved_imports: u32,
    /// The probe results. At approval the shell runs every probe in the
    /// same request.
    pub probes: ProbeSet,
    /// The live SoD previews.
    pub sod: SodPreview,
    /// The vault answers.
    pub vault: VaultChecks,
    /// The attested tenant admin set (Q31).
    pub tenant_admins: BTreeSet<AccountId>,
    /// The ports present.
    pub ports: PortPresence,
    /// The theme to check, the default theme in M4.
    pub theme: Theme,
    /// The draft's funder profile, from the cell's profile source. `None`
    /// fails the profile checks closed.
    pub profile: Option<FunderProfile>,
}

/// The vault questions the engine asks before a creator decision.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VaultQuestions {
    /// The accounts to ask `IsVerified` for: every builder, and the
    /// approver if any.
    pub is_verified: BTreeSet<AccountId>,
    /// `SameIdentityAsAny(approver, builders)`, if an approver is named.
    pub same_identity: Option<(AccountId, BTreeSet<AccountId>)>,
}

/// The vault questions for a report on `programme`, and for an approval
/// by `approver` if one is named.
pub fn vault_questions(
    creator: &CreatorState,
    programme: ProgrammeId,
    approver: Option<AccountId>,
) -> VaultQuestions {
    let builders = creator
        .draft(programme)
        .map(|d| d.builders().clone())
        .unwrap_or_default();
    let mut is_verified = builders.clone();
    if let Some(a) = approver {
        is_verified.insert(a);
    }
    VaultQuestions {
        is_verified,
        same_identity: approver.map(|a| (a, builders)),
    }
}

/// One invitation the engine previews with `preview_grant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreviewTarget {
    /// The invitation.
    pub invitation: InvitationId,
    /// The invited account.
    pub account: AccountId,
    /// The role.
    pub role: Role,
    /// The committee organisation.
    pub organisation: Option<OrganisationId>,
}

/// The live invitations of `programme` that have an account, in id order:
/// an invited account, or the account that accepted an invitation by
/// contact address. The engine runs `preview_grant` for each and records
/// every vault answer in the audit log (`overview.md` NOTE 5).
pub fn preview_targets(creator: &CreatorState, programme: ProgrammeId) -> Vec<PreviewTarget> {
    let Some(d) = creator.draft(programme) else {
        return Vec::new();
    };
    d.live_invitations()
        .filter_map(|(invitation, i)| {
            i.account().map(|account| PreviewTarget {
                invitation,
                account,
                role: i.role,
                organisation: i.organisation,
            })
        })
        .collect()
}
