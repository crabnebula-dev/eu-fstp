//! Account-level rules and identity candidate sets (design sections 2.6 and 4.2).
//!
//! - [`account_rule`] checks a new binding against the account's own
//!   bindings and bars: SoD-01, SoD-02, SoD-03 and SoD-05.
//! - [`identity_candidates`] builds the set `S` of the identity question:
//!   the other accounts whose held bindings or unexpired bars would break
//!   I-01 if they were the candidate's (I-06, SoD-09, overview NOTE 1).
//!   [`breaking_candidates`] builds it for any binding, ended ones
//!   included, for the reaction to a vault change.
//! - [`Target`] carries the one cooling-off comparison of the spec.

use std::collections::BTreeSet;

use crate::id::{AccountId, CallId, CallSeq, ProgrammeId};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{Group, Role};
use crate::state::State;

/// What a new binding is compared with in the cooling-off rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// A Drafting, Judging or Operations binding: the latest call sequence
    /// published in the programme now.
    Programme {
        /// The latest published sequence, 0 before any.
        latest: u32,
    },
    /// A Receiving binding: its call's sequence number.
    Call {
        /// The call's sequence number.
        seq: u32,
    },
}

impl Target {
    /// The opening of the new binding: the value a bar is compared with.
    pub(crate) const fn opened(self) -> u32 {
        match self {
            Target::Programme { latest } => latest,
            Target::Call { seq } => seq,
        }
    }

    /// Whether `bar` bars the new binding (Cooling-off section).
    pub(crate) const fn barred_by(self, bar: u32) -> bool {
        self.opened() <= bar
    }
}

/// The latest call sequence published in `programme` now, 0 before any (P-12 NOTE 4).
pub(crate) fn latest(state: &State, programme: ProgrammeId) -> u32 {
    crate::programme::latest_published_seq(state, programme).map_or(0, CallSeq::get)
}

/// The refusal for an unknown programme, call, proposal or binding.
pub(crate) const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The published call `call`: its programme and sequence number.
pub(crate) fn published_call(state: &State, call: CallId) -> Result<(ProgrammeId, u32), Refusal> {
    let view = crate::programme::call(state, call).ok_or_else(unknown)?;
    let seq = view
        .seq()
        .ok_or(Refusal::new(RuleRef::Input, RefusalReason::WrongState))?;
    Ok((view.programme(), seq.get()))
}

/// The rule a new binding of `role` for `account` in `programme` breaks
/// against the account's own bindings and bars, if any.
///
/// - SoD-01: a held binding of another group among Drafting, Judging and Receiving.
/// - SoD-05: a bar of another of those groups that bars `target`.
/// - SoD-03: a held Operations binding against a Receiving one, or the reverse.
/// - SoD-02: a held IRC binding against another Judging one, or the reverse.
///
/// Held bindings include suspended ones. Voided bindings never count.
pub(crate) fn account_rule(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    role: Role,
    target: Target,
) -> Option<RuleRef> {
    let group = role.group();
    for (_, b) in state.roster.bindings() {
        if b.account != account || b.programme != programme || !b.held() {
            continue;
        }
        let other = b.group();
        if group.separated() && other.separated() && other != group {
            return Some(RuleRef::Sod01);
        }
        let ops_receiving = matches!(
            (group, other),
            (Group::Operations, Group::Receiving) | (Group::Receiving, Group::Operations)
        );
        if ops_receiving {
            return Some(RuleRef::Sod03);
        }
        let irc_clash = (role == Role::IrcMember && b.role.other_judging())
            || (role.other_judging() && b.role == Role::IrcMember);
        if irc_clash {
            return Some(RuleRef::Sod02);
        }
    }
    if group.separated() {
        for other in Group::SEPARATED {
            if other == group {
                continue;
            }
            if state
                .roster
                .bar(programme, account, other)
                .is_some_and(|bar| target.barred_by(bar))
            {
                return Some(RuleRef::Sod05);
            }
        }
    }
    None
}

/// The candidate set `S` of the identity question for a new binding of
/// `subject` in `group` (overview NOTE 1).
///
/// It holds every other account of `programme` with a held binding of
/// another group among Drafting, Judging and Receiving, or with a bar of
/// such a group that bars `target`. Empty for an Operations binding.
pub(crate) fn identity_candidates(
    state: &State,
    subject: AccountId,
    programme: ProgrammeId,
    group: Group,
    target: Target,
) -> BTreeSet<AccountId> {
    breaking_candidates(
        state,
        subject,
        programme,
        &other_separated(group),
        target.opened(),
        None,
    )
}

/// The separated groups other than `group`. None for Operations.
pub(crate) fn other_separated(group: Group) -> Vec<Group> {
    if !group.separated() {
        return Vec::new();
    }
    Group::SEPARATED
        .into_iter()
        .filter(|g| *g != group)
        .collect()
}

/// The other accounts of `programme` with a binding in one of `groups`
/// that breaks I-01 with a binding of `subject` opened at `opened` and
/// barred through `bar`, if both accounts were one person.
///
/// `bar` is `None` while the binding is held. Two bindings of different
/// separated groups break I-01 together exactly when each opening is at
/// most the other's bar, a held binding having no bar. Overlapping
/// bindings always meet this, because every call sequence only grows.
/// Voided bindings never count.
pub(crate) fn breaking_candidates(
    state: &State,
    subject: AccountId,
    programme: ProgrammeId,
    groups: &[Group],
    opened: u32,
    bar: Option<u32>,
) -> BTreeSet<AccountId> {
    let covers = |other_opened: u32| bar.is_none_or(|b| other_opened <= b);
    let mut out = BTreeSet::new();
    for (_, b) in state.roster.bindings() {
        if b.account != subject
            && b.programme == programme
            && b.held()
            && groups.contains(&b.group())
            && covers(b.opened)
        {
            out.insert(b.account);
        }
    }
    for (_, e) in state.roster.ended() {
        let b = &e.binding;
        if b.account != subject
            && b.programme == programme
            && groups.contains(&b.group())
            && covers(b.opened)
            && e.live_bar().is_some_and(|other_bar| opened <= other_bar)
        {
            out.insert(b.account);
        }
    }
    out
}
